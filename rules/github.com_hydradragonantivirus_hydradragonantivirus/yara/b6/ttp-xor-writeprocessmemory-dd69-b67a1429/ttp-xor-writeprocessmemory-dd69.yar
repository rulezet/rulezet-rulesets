rule TTP_XOR_WriteProcessMemory_dd69 {
  strings:
    $key_dd69 = { 8a 1b [2] b8 39 [2] be 0c [2] 90 0c [2] af 10 }

  condition:
    any of them
}