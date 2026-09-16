rule TTP_XOR_WriteProcessMemory_0ccf {
  strings:
    $key_0ccf = { 5b bd [2] 69 9f [2] 6f aa [2] 41 aa [2] 7e b6 }

  condition:
    any of them
}