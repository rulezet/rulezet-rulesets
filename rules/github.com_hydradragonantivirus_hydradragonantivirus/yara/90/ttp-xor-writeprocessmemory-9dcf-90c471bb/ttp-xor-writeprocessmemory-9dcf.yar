rule TTP_XOR_WriteProcessMemory_9dcf {
  strings:
    $key_9dcf = { ca bd [2] f8 9f [2] fe aa [2] d0 aa [2] ef b6 }

  condition:
    any of them
}