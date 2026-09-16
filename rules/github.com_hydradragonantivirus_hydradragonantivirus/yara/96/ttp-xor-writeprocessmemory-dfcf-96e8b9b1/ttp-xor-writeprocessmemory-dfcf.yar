rule TTP_XOR_WriteProcessMemory_dfcf {
  strings:
    $key_dfcf = { 88 bd [2] ba 9f [2] bc aa [2] 92 aa [2] ad b6 }

  condition:
    any of them
}