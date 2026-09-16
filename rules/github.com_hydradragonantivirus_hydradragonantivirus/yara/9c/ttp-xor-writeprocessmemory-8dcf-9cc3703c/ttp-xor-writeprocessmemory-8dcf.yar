rule TTP_XOR_WriteProcessMemory_8dcf {
  strings:
    $key_8dcf = { da bd [2] e8 9f [2] ee aa [2] c0 aa [2] ff b6 }

  condition:
    any of them
}