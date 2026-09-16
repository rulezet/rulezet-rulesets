rule TTP_XOR_WriteProcessMemory_1dcf {
  strings:
    $key_1dcf = { 4a bd [2] 78 9f [2] 7e aa [2] 50 aa [2] 6f b6 }

  condition:
    any of them
}