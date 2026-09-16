rule TTP_XOR_WriteProcessMemory_cfcf {
  strings:
    $key_cfcf = { 98 bd [2] aa 9f [2] ac aa [2] 82 aa [2] bd b6 }

  condition:
    any of them
}