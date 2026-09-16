rule TTP_XOR_WriteProcessMemory_4ecf {
  strings:
    $key_4ecf = { 19 bd [2] 2b 9f [2] 2d aa [2] 03 aa [2] 3c b6 }

  condition:
    any of them
}