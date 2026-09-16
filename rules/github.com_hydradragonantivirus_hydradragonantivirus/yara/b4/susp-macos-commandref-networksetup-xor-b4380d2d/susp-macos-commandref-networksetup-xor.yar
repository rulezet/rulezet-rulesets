rule SUSP_MacOS_CommandRef_networksetup_xor {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-23"
    version     = "1.0"
    description = "check for references to networksetup utility"

  strings:
    $ = "networksetup" xor(0x01-0xff) ascii wide

  condition:
    all of them
}