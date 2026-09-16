rule TTP_XOR_WriteProcessMemory_bacf {
  strings:
    $key_bacf = { ed bd [2] df 9f [2] d9 aa [2] f7 aa [2] c8 b6 }

  condition:
    any of them
}