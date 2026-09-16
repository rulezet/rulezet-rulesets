rule TTP_XOR_WriteProcessMemory_aacf {
  strings:
    $key_aacf = { fd bd [2] cf 9f [2] c9 aa [2] e7 aa [2] d8 b6 }

  condition:
    any of them
}