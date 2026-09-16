rule PEiD_01505_PE_Packer_ {
  meta:
    description = "[PE Packer]"
    ep_only     = "true"

  strings:
    $a = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }

  condition:
    $a
}