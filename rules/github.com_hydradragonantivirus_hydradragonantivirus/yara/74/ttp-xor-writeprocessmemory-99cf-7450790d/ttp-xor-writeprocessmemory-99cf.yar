rule TTP_XOR_WriteProcessMemory_99cf {
  strings:
    $key_99cf = { ce bd [2] fc 9f [2] fa aa [2] d4 aa [2] eb b6 }

  condition:
    any of them
}