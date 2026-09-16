rule TTP_XOR_WriteProcessMemory_3dcf {
  strings:
    $key_3dcf = { 6a bd [2] 58 9f [2] 5e aa [2] 70 aa [2] 4f b6 }

  condition:
    any of them
}