rule TTP_XOR_WriteProcessMemory_b20c {
  strings:
    $key_b20c = { e5 7e [2] d7 5c [2] d1 69 [2] ff 69 [2] c0 75 }

  condition:
    any of them
}