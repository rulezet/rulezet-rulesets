rule TTP_XOR_WriteProcessMemory_8dee {
  strings:
    $key_8dee = { da 9c [2] e8 be [2] ee 8b [2] c0 8b [2] ff 97 }

  condition:
    any of them
}