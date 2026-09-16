rule TTP_XOR_WriteProcessMemory_cbcf {
  strings:
    $key_cbcf = { 9c bd [2] ae 9f [2] a8 aa [2] 86 aa [2] b9 b6 }

  condition:
    any of them
}