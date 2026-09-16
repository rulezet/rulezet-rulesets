rule APT28_IMPLANT_1_v7
{
meta:
      author = "US-CERT"
      description = "X-AGENT/CHOPSTICK"
      reference = "https://www.us-cert.gov/sites/default/files/publications/AR-17-20045_Enhanced_Analysis_of_GRIZZLY_STEPPE_Activity.pdf"

strings:
      $XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }

condition:
      (uint16(0) == 0x5A4D) and all of them
}