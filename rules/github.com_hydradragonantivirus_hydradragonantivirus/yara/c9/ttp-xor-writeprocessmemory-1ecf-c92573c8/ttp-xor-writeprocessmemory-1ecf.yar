rule TTP_XOR_WriteProcessMemory_1ecf {
  strings:
    $key_1ecf = { 49 bd [2] 7b 9f [2] 7d aa [2] 53 aa [2] 6c b6 }

  condition:
    any of them
}