rule TTP_XOR_WriteProcessMemory_0dcf {
  strings:
    $key_0dcf = { 5a bd [2] 68 9f [2] 6e aa [2] 40 aa [2] 7f b6 }

  condition:
    any of them
}