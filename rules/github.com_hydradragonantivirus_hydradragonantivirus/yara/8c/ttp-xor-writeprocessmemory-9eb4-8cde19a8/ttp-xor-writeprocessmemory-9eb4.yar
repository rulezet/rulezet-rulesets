rule TTP_XOR_WriteProcessMemory_9eb4 {
  strings:
    $key_9eb4 = { c9 c6 [2] fb e4 [2] fd d1 [2] d3 d1 [2] ec cd }

  condition:
    any of them
}