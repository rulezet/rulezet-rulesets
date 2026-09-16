rule SUSP_Obfuscated_Powershell_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $ = "powershell" xor(0x01-0xff) ascii wide
    $ = "Powershell" xor(0x01-0xff) ascii wide
    $ = "PowerShell" xor(0x01-0xff) ascii wide
    $ = "POWERSHELL" xor(0x01-0xff) ascii wide
  condition:
    any of them
}