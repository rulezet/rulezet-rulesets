rule TTP_XOR_WriteProcessMemory_9ccf {
  strings:
    $key_9ccf = { cb bd [2] f9 9f [2] ff aa [2] d1 aa [2] ee b6 }

  condition:
    any of them
}