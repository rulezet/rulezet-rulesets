rule TTP_XOR_WriteProcessMemory_82cf {
  strings:
    $key_82cf = { d5 bd [2] e7 9f [2] e1 aa [2] cf aa [2] f0 b6 }

  condition:
    any of them
}