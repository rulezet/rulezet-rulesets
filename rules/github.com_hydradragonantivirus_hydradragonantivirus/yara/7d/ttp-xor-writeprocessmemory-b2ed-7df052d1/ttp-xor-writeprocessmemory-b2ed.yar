rule TTP_XOR_WriteProcessMemory_b2ed {
  strings:
    $key_b2ed = { e5 9f [2] d7 bd [2] d1 88 [2] ff 88 [2] c0 94 }

  condition:
    any of them
}