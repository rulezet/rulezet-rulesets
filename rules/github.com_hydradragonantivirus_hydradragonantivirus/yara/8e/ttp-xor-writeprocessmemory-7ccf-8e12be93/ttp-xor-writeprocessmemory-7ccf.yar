rule TTP_XOR_WriteProcessMemory_7ccf {
  strings:
    $key_7ccf = { 2b bd [2] 19 9f [2] 1f aa [2] 31 aa [2] 0e b6 }

  condition:
    any of them
}