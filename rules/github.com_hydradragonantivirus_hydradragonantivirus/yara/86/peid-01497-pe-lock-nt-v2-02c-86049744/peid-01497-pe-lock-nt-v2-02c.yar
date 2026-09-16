rule PEiD_01497_PE_Lock_NT_v2_02c_ {
  meta:
    description = "[PE Lock NT v2.02c]"
    ep_only     = "true"

  strings:
    $a = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

  condition:
    $a
}