rule loader_win_piccassoloader {
  meta:
    id             = "91d9c2de-451e-467e-8f5c-38bbcce92b72"
    version        = "1.0"
    description    = "Detect the variant of Picasso used by GhostWriter as CVE-2023-38831 exploitation payload"
    author         = "Sekoia.io"
    creation_date  = "2023-09-07"
    classification = "TLP:CLEAR"

  strings:
    $ = ",'Decryptor','node','User-"
    $ = "\\x20Chrome/10','gger','sedCipher','_append','_ENC_XFORM','WScript.Sh'"

  condition:
    1 of them
}