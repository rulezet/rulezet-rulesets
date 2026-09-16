rule TTP_XOR_WriteProcessMemory_cccf {
  strings:
    $key_cccf = { 9b bd [2] a9 9f [2] af aa [2] 81 aa [2] be b6 }

  condition:
    any of them
}