rule TTP_XOR_WriteProcessMemory_2ccf {
  strings:
    $key_2ccf = { 7b bd [2] 49 9f [2] 4f aa [2] 61 aa [2] 5e b6 }

  condition:
    any of them
}