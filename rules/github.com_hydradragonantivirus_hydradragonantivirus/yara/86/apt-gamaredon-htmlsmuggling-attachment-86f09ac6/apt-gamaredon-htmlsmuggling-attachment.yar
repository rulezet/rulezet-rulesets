rule apt_GAMAREDON_HTMLSmuggling_Attachment {
  meta:
    id             = "a39b6e67-9327-4c5b-902a-b9853cfefc8e"
    version        = "1.0"
    intrusion_set  = "Gamaredon"
    description    = "Detects Gamaredon HTMLSmuggling attachment"
    source         = "SEKOIA"
    creation_date  = "2023-01-20"
    classification = "TLP:WHITE"

  strings:
    $ = "['at'+'ob'](" ascii
    $ = "['ev'+'al'](" ascii
    $ = "document.querySelectorAll('[" ascii
    $ = "[0].innerHTML.split(' ').join('')))" ascii

  condition:
    filesize < 1MB and
    2 of them
}