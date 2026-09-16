rule TTP_XOR_WriteProcessMemory_87cf {
  strings:
    $key_87cf = { d0 bd [2] e2 9f [2] e4 aa [2] ca aa [2] f5 b6 }

  condition:
    any of them
}