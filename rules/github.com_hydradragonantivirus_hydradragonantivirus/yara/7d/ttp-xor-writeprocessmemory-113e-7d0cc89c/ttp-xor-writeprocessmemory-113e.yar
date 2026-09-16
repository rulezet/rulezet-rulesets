rule TTP_XOR_WriteProcessMemory_113e {
  strings:
    $key_113e = { 46 4c [2] 74 6e [2] 72 5b [2] 5c 5b [2] 63 47 }

  condition:
    any of them
}