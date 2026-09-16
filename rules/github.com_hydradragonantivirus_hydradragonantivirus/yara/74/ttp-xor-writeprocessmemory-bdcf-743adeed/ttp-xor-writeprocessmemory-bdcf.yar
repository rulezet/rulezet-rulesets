rule TTP_XOR_WriteProcessMemory_bdcf {
  strings:
    $key_bdcf = { ea bd [2] d8 9f [2] de aa [2] f0 aa [2] cf b6 }

  condition:
    any of them
}