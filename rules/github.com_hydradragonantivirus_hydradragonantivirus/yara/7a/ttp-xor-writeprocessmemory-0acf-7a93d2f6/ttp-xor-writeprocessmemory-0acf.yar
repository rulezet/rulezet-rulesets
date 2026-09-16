rule TTP_XOR_WriteProcessMemory_0acf {
  strings:
    $key_0acf = { 5d bd [2] 6f 9f [2] 69 aa [2] 47 aa [2] 78 b6 }

  condition:
    any of them
}