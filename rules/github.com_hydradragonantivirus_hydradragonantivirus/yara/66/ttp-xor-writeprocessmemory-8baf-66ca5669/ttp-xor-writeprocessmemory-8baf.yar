rule TTP_XOR_WriteProcessMemory_8baf {
  strings:
    $key_8baf = { dc dd [2] ee ff [2] e8 ca [2] c6 ca [2] f9 d6 }

  condition:
    any of them
}