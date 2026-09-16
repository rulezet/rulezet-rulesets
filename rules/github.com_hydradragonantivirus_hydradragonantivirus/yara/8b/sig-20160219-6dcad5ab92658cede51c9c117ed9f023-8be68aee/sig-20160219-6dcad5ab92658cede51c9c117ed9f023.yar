rule sig_20160219_6dcad5ab92658cede51c9c117ed9f023 {
  meta:
    description = "datamaliciousorder - file 20160219_6dcad5ab92658cede51c9c117ed9f023.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73a3d57b5ff9c39ae995c015f1a40f5259fe6e17cc9d981382e92a49b6e28f24"

  strings:
    $x1 = " profileDefect=eval(('coordination', 'alternative', 'demon', 'legal', '\\u0074parity'.e()) + 'h' + ('economy', 'progression', 'c" ascii
    $s2 = "produce'.e()) + 'e' + ('dialect', 'switch', 'command', 'aviation', '\\u006eregression'.e()) + 'd'](); while (publicRobot[('stude" ascii
    $s3 = "gy', 'paragraph', '\\u0065cooperation'.e()) + ''] < ((1*0)^(2+2))) {this[('season', 'price-list', 'industry', 'criteria', 'print" ascii
    $s4 = "port', 'energy', '\\u0072protocol'.e()) + 'e' + ('figure', '\\u0061barrier'.e()) + 'm'); try { impressionBarge[('special', 'thes" ascii
    $s5 = "rt'.e()) + ''; function String.prototype.e(a) {return this.charAt(a);} decadeFacade = new profileDefect(('packet', '\\u0057blank" ascii
    $s6 = "cohol', 'illusion', '\\u002fprofile'.e()) + 'l' + ('emission', 'absurd', '\\u006fphenomenon'.e()) + 'gs' + ('formula', 'segment'" ascii
    $s7 = "shorts', '\\u0053atom'.e()) + 'l' + ('reorganize', 'memoirs', 'tariff', 'instrument', '\\u0065master'.e()) + 'e' + ('genesis', '" ascii
    $s8 = "club', 'fortune', '\\u006dcommunication'.e()) + 'en' + ('lethal', 'spindle', '\\u0074mandate'.e()) + 'St' + ('theoretic', 'gigan" ascii
    $s9 = "](computerProgression); } catch (jungleDiscrete) {}; } catch (jungleDiscrete) {}; " fullword ascii

  condition:
    uint16(0) == 0x7020 and
    1 of ($x*) and all of them
}