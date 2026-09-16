rule TTP_XOR_WriteProcessMemory_4bcf {
  strings:
    $key_4bcf = { 1c bd [2] 2e 9f [2] 28 aa [2] 06 aa [2] 39 b6 }

  condition:
    any of them
}