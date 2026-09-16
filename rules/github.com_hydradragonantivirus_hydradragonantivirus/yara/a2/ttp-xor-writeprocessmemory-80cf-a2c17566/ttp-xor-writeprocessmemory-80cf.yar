rule TTP_XOR_WriteProcessMemory_80cf {
  strings:
    $key_80cf = { d7 bd [2] e5 9f [2] e3 aa [2] cd aa [2] f2 b6 }

  condition:
    any of them
}