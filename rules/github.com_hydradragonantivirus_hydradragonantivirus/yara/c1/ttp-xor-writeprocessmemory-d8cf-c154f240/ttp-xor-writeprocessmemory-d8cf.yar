rule TTP_XOR_WriteProcessMemory_d8cf {
  strings:
    $key_d8cf = { 8f bd [2] bd 9f [2] bb aa [2] 95 aa [2] aa b6 }

  condition:
    any of them
}