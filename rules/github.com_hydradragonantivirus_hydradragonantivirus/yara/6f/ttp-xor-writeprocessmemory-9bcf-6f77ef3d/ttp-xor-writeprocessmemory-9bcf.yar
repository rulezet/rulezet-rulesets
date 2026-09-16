rule TTP_XOR_WriteProcessMemory_9bcf {
  strings:
    $key_9bcf = { cc bd [2] fe 9f [2] f8 aa [2] d6 aa [2] e9 b6 }

  condition:
    any of them
}