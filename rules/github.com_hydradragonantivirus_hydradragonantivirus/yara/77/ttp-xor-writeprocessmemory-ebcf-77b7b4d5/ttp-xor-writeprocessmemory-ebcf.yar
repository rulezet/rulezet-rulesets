rule TTP_XOR_WriteProcessMemory_ebcf {
  strings:
    $key_ebcf = { bc bd [2] 8e 9f [2] 88 aa [2] a6 aa [2] 99 b6 }

  condition:
    any of them
}