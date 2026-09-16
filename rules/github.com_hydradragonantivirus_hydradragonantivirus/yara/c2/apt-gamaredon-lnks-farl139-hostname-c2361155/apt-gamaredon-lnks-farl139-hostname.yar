rule apt_Gamaredon_LNKs_farl139_hostname {
  meta:
    id             = "f8bb2e6b-e544-46b0-b61b-048fe84e1100"
    version        = "1.0"
    intrusion_set  = "Gamaredon"
    description    = "Detects some hostname used in Gamaredon LNKs"
    source         = "SEKOIA"
    creation_date  = "2023-01-20"
    classification = "TLP:WHITE"

  strings:
    $ = "desktop-farl139"

  condition:
    uint32be(0) == 0x4c000000
    and all of them
    and filesize < 10KB
}