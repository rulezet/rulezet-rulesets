rule TTP_XOR_WriteProcessMemory_02cf {
  strings:
    $key_02cf = { 55 bd [2] 67 9f [2] 61 aa [2] 4f aa [2] 70 b6 }

  condition:
    any of them
}