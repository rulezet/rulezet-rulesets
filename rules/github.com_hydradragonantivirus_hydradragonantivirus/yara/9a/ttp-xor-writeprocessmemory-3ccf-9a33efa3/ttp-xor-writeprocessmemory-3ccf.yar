rule TTP_XOR_WriteProcessMemory_3ccf {
  strings:
    $key_3ccf = { 6b bd [2] 59 9f [2] 5f aa [2] 71 aa [2] 4e b6 }

  condition:
    any of them
}