rule TTP_XOR_WriteProcessMemory_eecf {
  strings:
    $key_eecf = { b9 bd [2] 8b 9f [2] 8d aa [2] a3 aa [2] 9c b6 }

  condition:
    any of them
}