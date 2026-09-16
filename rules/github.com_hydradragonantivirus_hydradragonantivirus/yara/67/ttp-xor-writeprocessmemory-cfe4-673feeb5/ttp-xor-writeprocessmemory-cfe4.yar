rule TTP_XOR_WriteProcessMemory_cfe4 {
  strings:
    $key_cfe4 = { 98 96 [2] aa b4 [2] ac 81 [2] 82 81 [2] bd 9d }

  condition:
    any of them
}