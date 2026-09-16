rule sig_20170130_7ab90b1507bc742c3f211f35b214d9f6 {
  meta:
    description = "datamaliciousorder - file 20170130_7ab90b1507bc742c3f211f35b214d9f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6d14ee277cebcee7215e8198b8ae39fbb709bc2528857c4cc9c0ec5f8493ac6"

  strings:
    $s1  = "vymtafkapnaqlojapzewjyttihgykexuclecuchinavcowxedanilemozotudugtuhifojuvfyjaxlonlinfuxpawepokcoctymudinubwuvhyfdiqcapqunyjkyklom" ascii
    $s2  = "asyqjazamgaxgohubbugehjaftovyvucvubehahaqhynenidyclukvowuhyjebxufemynzubexopuhdepocpipredcubmarigkohvacoqudpetcytpysybxemahdesel" ascii
    $s3  = "asyqjazamgaxgohubbugehjaftovyvucvubehahaqhynenidyclukvowuhyjebxufemynzubexopuhdepocpipredcubmarigkohvacoqudpetcytpysybxemahdesel" ascii
    $s4  = "asyqjazamgaxgohubbugehjaftovyvucvubehahaqhynenidyclukvowuhyjebxufemynzubexopuhdepocpipredcubmarigkohvacoqudpetcytpysybxemahdesel" ascii
    $s5  = "asyqjazamgaxgohubbugehjaftovyvucvubehahaqhynenidyclukvowuhyjebxufemynzubexopuhdepocpipredcubmarigkohvacoqudpetcytpysybxemahdesel" ascii
    $s6  = "xojhiphywxemjipzydpytfocakkixowidjisergitkupjukqazfognaqibdyteqbyqikdafujmobrucmumusgofziqtutxohbibboccinahebmuciwavrusasdifolcu" ascii
    $s7  = "radrimimyryzybwufascimcyfopzemgicocizafexequmguchyfippo0[[\"uxnu900nhuqa\", true, \"gnaw190ila\", [\"qbyli577qtejb\", \"Get\"], " ascii
    $s8  = " \"gi527okc\", \"yqx638lu\", \"ejip619opgeql\"][4][1]]([true, \"ova222eg\", true, \"ade888fosb\", true, [\"imub404yq\", \"uzg801" ascii
    $s9  = "axs\"][4][0] + [true, true, true, \"iqx767zusf\", [\"/g\", true, true], true, true, \"ojf501sexi\", true, true, \"ivledl369hiqo" ascii
    $s10 = "dixa671iql\", \"lund864obk\", [\"ri\", \"akzegp547bedgu\", true], true, true, \"ochyq784ezl\", \"oftynw208wo\"][7][0] + [\"eve36" ascii
    $s11 = "sa546zvolpe\", true, \"uvc684wpunz\", [true, \"m =\"], true, true, \"jib914ynhi\", \"uch493icy\", true, true, \"xzunz730pqa\"][4" ascii
    $s12 = "epo\", \"ih293lihde\"][8][0] + [\"vgyc750ese\", true, \"uwjum930hfobtu\", \"oqyx596bgo\", \"xxofta105wtadu\", \"mhu549yju\", \"a" ascii
    $s13 = "\", [\"in\", true], \"uxfoxt132elbewf\", \"uzy191privz\", \"maki448ekty\"][6][0] + [true, \"ej283ojk\", true, true, true, true, " ascii
    $s14 = "wjeq\", \"bypte973iqn\", true, true, \"iqdo950otdy\"][5][1] + [[true, \"ufat315vjilmi\", \"cr\"], true, \"ecgic665un\", true, \"" ascii
    $s15 = "75ehqar\", true, true, true][1][1] + [\"kkecs686anh\", \"ecu898wi\", \"vjy137uhxul\", true, \"idal809emdel\", \"ex605lnuqa\", [" ascii
    $s16 = "3ovqets\", true, \"kvis324fokni\", \"mlegx520ulg\", true, true, [\"abu660als\", \"ype\", true], \"aje650nu\", true, \"ow841ydwe" ascii
    $s17 = "376wny\", \"wru775ehqar\", true, true, true][1][1] + [\"kkecs686anh\", \"ecu898wi\", \"vjy137uhxul\", true, \"idal809emdel\", \"" ascii
    $s18 = "uhz\", true, \"mleb312hdakk\", true, [true, true, \"le\"], true, \"ogpal462aris\", true][6][2] + [[\"fdij835amsamr\", \"Sy\", tr" ascii
    $s19 = "t160vwu\"], \"mit390ezcer\"][9][0] + [true, true, \"hawy642qehy\", \"vza579cka\", [\"').\", \"jxotsy710zqolri\"], true, \"afbi12" ascii
    $s20 = "62etpy\", true, \"qi223mtyfl\", true, \"amosh693elz\", true, \"hnal713qu\", true, true, \"ypr283hwiha\", \"patx274dsas\"][0][1] " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}