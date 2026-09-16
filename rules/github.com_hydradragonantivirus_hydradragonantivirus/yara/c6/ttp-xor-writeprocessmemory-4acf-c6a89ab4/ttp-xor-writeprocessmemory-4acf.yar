rule TTP_XOR_WriteProcessMemory_4acf {
  strings:
    $key_4acf = { 1d bd [2] 2f 9f [2] 29 aa [2] 07 aa [2] 38 b6 }

  condition:
    any of them
}