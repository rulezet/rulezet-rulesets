rule TTP_XOR_WriteProcessMemory_8acf {
  strings:
    $key_8acf = { dd bd [2] ef 9f [2] e9 aa [2] c7 aa [2] f8 b6 }

  condition:
    any of them
}