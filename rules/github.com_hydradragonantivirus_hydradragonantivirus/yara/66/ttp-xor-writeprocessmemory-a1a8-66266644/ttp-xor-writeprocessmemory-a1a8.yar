rule TTP_XOR_WriteProcessMemory_a1a8 {
  strings:
    $key_a1a8 = { f6 da [2] c4 f8 [2] c2 cd [2] ec cd [2] d3 d1 }

  condition:
    any of them
}