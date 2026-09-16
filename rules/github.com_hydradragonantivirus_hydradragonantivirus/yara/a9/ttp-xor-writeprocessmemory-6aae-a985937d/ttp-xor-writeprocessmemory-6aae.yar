rule TTP_XOR_WriteProcessMemory_6aae {
  strings:
    $key_6aae = { 3d dc [2] 0f fe [2] 09 cb [2] 27 cb [2] 18 d7 }

  condition:
    any of them
}