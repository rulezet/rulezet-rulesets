rule rat_win_lilith {
  meta:
    id             = "944637e6-c4e4-423f-9f4c-a26b4fce3729"
    version        = "1.0"
    description    = "Detect the Lilith malware"
    author         = "Sekoia.io"
    creation_date  = "2023-02-23"
    classification = "TLP:CLEAR"

  strings:
        $ = "UmVnUXVlcnlWYWx1ZUV4QQ=="
        $ = "getaddrinfo: %s"

  condition:
    all of them
}