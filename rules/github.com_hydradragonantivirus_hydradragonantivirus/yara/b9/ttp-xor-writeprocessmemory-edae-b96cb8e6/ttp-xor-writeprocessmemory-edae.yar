rule TTP_XOR_WriteProcessMemory_edae {
  strings:
    $key_edae = { ba dc [2] 88 fe [2] 8e cb [2] a0 cb [2] 9f d7 }

  condition:
    any of them
}